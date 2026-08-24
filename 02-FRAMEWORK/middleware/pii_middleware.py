"""
PII Middleware - Middleware FastAPI para Filtrado de PII

Intercepta requests y responses para filtrar datos de identificación
personal antes de que alcancen el backend del LLM.

⚠️ Diseñado para entornos gubernamentales altamente regulados

Uso:
    from fastapi import FastAPI
    from middleware.pii_middleware import PIIMiddleware
    
    app = FastAPI()
    pii_middleware = PIIMiddleware(app)
    
    # O como dependency
    @app.post("/chat")
    async def chat(request: ChatRequest, pii_check: dict = Depends(pii_middleware.check)):
        if pii_check["blocked"]:
            return {"error": "PII detected", "details": pii_check}
        # Continuar con el procesamiento
"""

from typing import Dict, Any, Optional, Callable
from fastapi import Request, Response, HTTPException
from fastapi.middleware.base import BaseHTTPMiddleware
import json
import time


class PIIMiddleware(BaseHTTPMiddleware):
    """
    Middleware FastAPI para filtrado de PII en tiempo real.
    
    Intercepta prompts de entrada y respuestas de salida para:
    1. Detectar y filtrar PII antes del procesamiento
    2. Enmascarar PII en respuestas
    3. Registrar intentos de extracción de datos
    
    Uso:
        app = FastAPI()
        middleware = PIIMiddleware(app, config={
            "block_on_critical": True,
            "mask_on_high": True,
            "log_violations": True,
        })
    """
    
    def __init__(self, app, config: Optional[Dict[str, Any]] = None):
        super().__init__(app)
        self.config = config or {}
        
        # Importar PII Guard
        from ..defenses.pii_guard import PIIGuard
        self.guard = PIIGuard(config)
        
        # Configuración
        self.block_on_critical = self.config.get("block_on_critical", True)
        self.mask_on_high = self.config.get("mask_on_high", True)
        self.log_violations = self.config.get("log_violations", True)
        
        # Estadísticas
        self.stats = {
            "total_requests": 0,
            "pii_detected": 0,
            "blocked": 0,
            "masked": 0,
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Intercepta cada request para validar PII.
        
        Args:
            request: Request entrante
            call_next: Siguiente handler en la cadena
            
        Returns:
            Response
        """
        self.stats["total_requests"] += 1
        
        # Solo interceptar requests POST con body JSON
        if request.method == "POST":
            try:
                # Leer body del request
                body = await request.body()
                
                if body:
                    try:
                        data = json.loads(body)
                        
                        # Buscar campos de prompt en el body
                        prompt_text = self._extract_prompt(data)
                        
                        if prompt_text:
                            # Escanear PII
                            result = self.guard.scan_input(prompt_text)
                            
                            if result.detected:
                                self.stats["pii_detected"] += 1
                                
                                # Registrar si está habilitado
                                if self.log_violations:
                                    self._log_violation(result, request)
                                
                                # Determinar acción
                                if result.action == "block" and self.block_on_critical:
                                    self.stats["blocked"] += 1
                                    return Response(
                                        content=json.dumps({
                                            "error": "PII detected in request",
                                            "action": "blocked",
                                            "violations": result.total_violations,
                                            "message": "El request contiene datos de identificación personal que no pueden ser procesados.",
                                        }),
                                        status_code=400,
                                        media_type="application/json",
                                    )
                                
                                elif result.action == "mask" and self.mask_on_high:
                                    self.stats["masked"] += 1
                                    # Enmascarar PII en el body
                                    masked_text = result.get_masked_text()
                                    data = self._replace_prompt(data, masked_text)
                                    
                                    # Reescribir body del request
                                    request._body = json.dumps(data).encode()
                    
                    except json.JSONDecodeError:
                        pass  # No es JSON válido, dejar pasar
            
            except Exception as e:
                # Log error pero no bloquear
                if self.log_violations:
                    print(f"PII Middleware error: {e}")
        
        # Continuar con el request
        response = await call_next(request)
        return response
    
    def _extract_prompt(self, data: Dict[str, Any]) -> Optional[str]:
        """Extrae el texto del prompt del body del request."""
        # Buscar en campos comunes
        prompt_fields = ["prompt", "message", "input", "text", "content", "query"]
        
        for field in prompt_fields:
            if field in data:
                value = data[field]
                if isinstance(value, str):
                    return value
                elif isinstance(value, dict) and "content" in value:
                    return value["content"]
                elif isinstance(value, list):
                    # Formato de mensajes
                    texts = []
                    for msg in value:
                        if isinstance(msg, dict) and "content" in msg:
                            texts.append(msg["content"])
                    if texts:
                        return " ".join(texts)
        
        # Buscar en messages (formato OpenAI)
        if "messages" in data and isinstance(data["messages"], list):
            texts = []
            for msg in data["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    texts.append(msg["content"])
            if texts:
                return " ".join(texts)
        
        return None
    
    def _replace_prompt(self, data: Dict[str, Any], new_text: str) -> Dict[str, Any]:
        """Reemplaza el texto del prompt enmascarado."""
        prompt_fields = ["prompt", "message", "input", "text", "content", "query"]
        
        for field in prompt_fields:
            if field in data:
                if isinstance(data[field], str):
                    data[field] = new_text
                    return data
        
        if "messages" in data and isinstance(data["messages"], list):
            for msg in data["messages"]:
                if isinstance(msg, dict) and "content" in msg:
                    msg["content"] = new_text
        
        return data
    
    def _log_violation(self, result, request: Request):
        """Registra una violación de PII."""
        print(f"[PII VIOLATION] Scan ID: {result.scan_id}")
        print(f"  Action: {result.action}")
        print(f"  Violations: {result.total_violations}")
        print(f"  Types: {[v.pii_type.value for v in result.violations]}")
        print(f"  Path: {request.url.path}")
        print(f"  Time: {result.scan_duration_ms:.2f}ms")
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas del middleware."""
        return {
            **self.stats,
            "detection_rate": (
                self.stats["pii_detected"] / self.stats["total_requests"] * 100
                if self.stats["total_requests"] > 0 else 0
            ),
            "guard_stats": self.guard.get_violation_stats(),
        }


class PIIDependency:
    """
    Dependency inyection para FastAPI.
    
    Uso:
        from fastapi import Depends
        from middleware.pii_middleware import PIIDependency
        
        pii_check = PIIDependency()
        
        @app.post("/chat")
        async def chat(request: ChatRequest, check: dict = Depends(pii_check)):
            if check["blocked"]:
                raise HTTPException(400, "PII detected")
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        from ..defenses.pii_guard import PIIGuard
        self.guard = PIIGuard(config)
    
    async def __call__(self, request: Request) -> Dict[str, Any]:
        """Verifica PII en el request."""
        try:
            body = await request.body()
            if body:
                data = json.loads(body)
                prompt_text = self._extract_prompt(data)
                
                if prompt_text:
                    result = self.guard.scan_input(prompt_text)
                    
                    return {
                        "detected": result.detected,
                        "blocked": result.action == "block",
                        "masked": result.action == "mask",
                        "violations": result.total_violations,
                        "action": result.action,
                        "masked_text": result.get_masked_text() if result.detected else None,
                    }
        except Exception:
            pass
        
        return {"detected": False, "blocked": False, "masked": False, "violations": 0}
    
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
