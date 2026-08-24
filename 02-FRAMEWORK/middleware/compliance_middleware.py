"""
Compliance Middleware - Middleware FastAPI para Filtrado de Cumplimiento

Intercepta requests y responses para filtrar:
- Secretos de Estado
- Manipulación geopolítica
- Intentos de extracción de contexto

⚠️ Diseñado para entornos gubernamentales altamente regulados

Uso:
    from fastapi import FastAPI
    from middleware.compliance_middleware import ComplianceMiddleware
    
    app = FastAPI()
    compliance = ComplianceMiddleware(app)
"""

from typing import Dict, Any, Optional, Callable
from fastapi import Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware
import json


class ComplianceMiddleware(BaseHTTPMiddleware):
    """
    Middleware FastAPI para filtrado de cumplimiento normativo.
    
    Intercepta requests para detectar:
    1. Intentos de extraer secretos de Estado
    2. Manipulación geopolítica
    3. Violasiones de soberanía territorial
    4. Ataques a la neutralidad institucional
    
    Uso:
        app = FastAPI()
        middleware = ComplianceMiddleware(app, config={
            "block_critical": True,
            "escalate_high": True,
        })
    """
    
    def __init__(self, app, config: Optional[Dict[str, Any]] = None):
        super().__init__(app)
        self.config = config or {}
        
        # Importar Compliance Filter
        from ..defenses.compliance_filter import ComplianceFilter
        self.filter = ComplianceFilter(config)
        
        # Configuración
        self.block_critical = self.config.get("block_critical", True)
        self.escalate_high = self.config.get("escalate_high", True)
        
        # Estadísticas
        self.stats = {
            "total_requests": 0,
            "violations_detected": 0,
            "blocked": 0,
            "escalated": 0,
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Intercepta requests para validar cumplimiento."""
        self.stats["total_requests"] += 1
        
        if request.method == "POST":
            try:
                body = await request.body()
                
                if body:
                    try:
                        data = json.loads(body)
                        prompt_text = self._extract_prompt(data)
                        
                        if prompt_text:
                            result = self.filter.scan(prompt_text)
                            
                            if result.detected:
                                self.stats["violations_detected"] += 1
                                
                                # Bloquear violaciones críticas
                                if result.action == "block" and self.block_critical:
                                    self.stats["blocked"] += 1
                                    return Response(
                                        content=json.dumps({
                                            "error": "Compliance violation detected",
                                            "action": "blocked",
                                            "violations": result.total_violations,
                                            "types": list(result.violations_by_type.keys()),
                                            "message": "La solicitud viola las políticas de cumplimiento normativo.",
                                        }),
                                        status_code=403,
                                        media_type="application/json",
                                    )
                                
                                # Escalar violaciones altas
                                elif result.action == "escalate" and self.escalate_high:
                                    self.stats["escalated"] += 1
                                    # Registrar para revisión pero permitir continuar
                                    self._log_escalation(result, request)
                    
                    except json.JSONDecodeError:
                        pass
            
            except Exception as e:
                print(f"Compliance Middleware error: {e}")
        
        response = await call_next(request)
        return response
    
    def _extract_prompt(self, data: Dict[str, Any]) -> Optional[str]:
        """Extrae el texto del prompt."""
        prompt_fields = ["prompt", "message", "input", "text", "content", "query"]
        
        for field in prompt_fields:
            if field in data and isinstance(data[field], str):
                return data[field]
        
        if "messages" in data and isinstance(data["messages"], list):
            texts = []
            for msg in data["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    texts.append(msg["content"])
            if texts:
                return " ".join(texts)
        
        return None
    
    def _log_escalation(self, result, request: Request):
        """Registra escalamiento para revisión."""
        print(f"[COMPLIANCE ESCALATION] Scan ID: {result.scan_id}")
        print(f"  Action: {result.action}")
        print(f"  Violations: {result.total_violations}")
        print(f"  Types: {list(result.violations_by_type.keys())}")
        print(f"  Path: {request.url.path}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas del middleware."""
        return {
            **self.stats,
            "violation_rate": (
                self.stats["violations_detected"] / self.stats["total_requests"] * 100
                if self.stats["total_requests"] > 0 else 0
            ),
            "filter_stats": self.filter.get_violation_stats(),
        }
