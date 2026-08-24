"""
Alignment Middleware - Middleware FastAPI para Verificación de Alineación

Intercepta requests y responses para verificar:
- Neutralidad institucional
- Rechazo de premisas falsas
- Ausencia de sesgo
- Tono apropiado

⚠️ Pre + Post análisis para cobertura completa

Uso:
    from fastapi import FastAPI
    from middleware.alignment_middleware import AlignmentMiddleware
    
    app = FastAPI()
    alignment = AlignmentMiddleware(app)
"""

from typing import Dict, Any, Optional, Callable
from fastapi import Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware
import json


class AlignmentMiddleware(BaseHTTPMiddleware):
    """
    Middleware FastAPI para verificación de alineación institucional.
    
    Implementa análisis Pre + Post:
    1. PRE-FILTRO: Valida prompts antes del procesamiento
    2. POST-ANÁLISIS: Valida respuestas después del procesamiento
    
    Uso:
        app = FastAPI()
        middleware = AlignmentMiddleware(app, config={
            "block_critical_pre": True,
            "regenerate_on_violation": True,
        })
    """
    
    def __init__(self, app, config: Optional[Dict[str, Any]] = None):
        super().__init__(app)
        self.config = config or {}
        
        # Importar Alignment Module
        from ..defenses.alignment_module import AlignmentModule
        self.module = AlignmentModule(config)
        
        # Configuración
        self.block_critical_pre = self.config.get("block_critical_pre", True)
        self.regenerate_on_violation = self.config.get("regenerate_on_violation", True)
        
        # Estadísticas
        self.stats = {
            "total_requests": 0,
            "pre_filter_violations": 0,
            "post_analysis_violations": 0,
            "blocked_pre": 0,
            "regenerated": 0,
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Intercepta requests para verificar alineación."""
        self.stats["total_requests"] += 1
        
        prompt_text = None
        
        # PRE-FILTRO
        if request.method == "POST":
            try:
                body = await request.body()
                
                if body:
                    try:
                        data = json.loads(body)
                        prompt_text = self._extract_prompt(data)
                        
                        if prompt_text:
                            pre_result = self.module.pre_filter(prompt_text)
                            
                            if pre_result["detected"]:
                                self.stats["pre_filter_violations"] += 1
                                
                                if pre_result["action"] == "block" and self.block_critical_pre:
                                    self.stats["blocked_pre"] += 1
                                    return Response(
                                        content=json.dumps({
                                            "error": "Alignment violation detected in prompt",
                                            "action": "blocked",
                                            "violations": len(pre_result["violations"]),
                                            "strategy": "reject_premise_with_facts",
                                            "message": "La solicitud contiene premisas que violan la neutralidad institucional.",
                                        }),
                                        status_code=400,
                                        media_type="application/json",
                                    )
                                
                                elif pre_result["action"] == "modify_prompt":
                                    # Reescribir prompt de forma neutral
                                    neutral_prompt = self.module.rewrite_neutral(prompt_text)
                                    data = self._replace_prompt(data, neutral_prompt)
                                    request._body = json.dumps(data).encode()
                    
                    except json.JSONDecodeError:
                        pass
            
            except Exception as e:
                print(f"Alignment Middleware error: {e}")
        
        # Ejecutar request
        response = await call_next(request)
        
        # POST-ANÁLISIS (solo para responses exitosas)
        if response.status_code == 200 and prompt_text:
            try:
                # Leer response body
                response_body = b""
                async for chunk in response.body_iterator:
                    if isinstance(chunk, str):
                        response_body += chunk.encode()
                    else:
                        response_body += chunk
                
                # Intentar parsear como JSON
                try:
                    response_data = json.loads(response_body)
                    response_text = self._extract_response_text(response_data)
                    
                    if response_text:
                        post_result = self.module.post_analyze(response_text, prompt_text)
                        
                        if post_result["detected"]:
                            self.stats["post_analysis_violations"] += 1
                            
                            if post_result["action"] == "regenerate" and self.regenerate_on_violation:
                                self.stats["regenerated"] += 1
                                # Retornar respuesta indicando que se debe regenerar
                                return Response(
                                    content=json.dumps({
                                        "error": "Alignment violation in response",
                                        "action": "regenerate",
                                        "violations": len(post_result["violations"]),
                                        "message": "La respuesta generada contiene desviaciones de alineación.",
                                    }),
                                    status_code=200,
                                    media_type="application/json",
                                )
                
                except json.JSONDecodeError:
                    pass
                
                # Restaurar response original
                return Response(
                    content=response_body,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.media_type,
                )
            
            except Exception as e:
                print(f"Alignment post-analysis error: {e}")
        
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
    
    def _extract_response_text(self, data: Dict[str, Any]) -> Optional[str]:
        """Extrae el texto de la respuesta."""
        # Formato OpenAI
        if "choices" in data and isinstance(data["choices"], list):
            for choice in data["choices"]:
                if "message" in choice and "content" in choice["message"]:
                    return choice["message"]["content"]
        
        # Formato Anthropic
        if "content" in data and isinstance(data["content"], list):
            texts = []
            for block in data["content"]:
                if isinstance(block, dict) and "text" in block:
                    texts.append(block["text"])
            if texts:
                return " ".join(texts)
        
        # Formato genérico
        if "response" in data and isinstance(data["response"], str):
            return data["response"]
        
        if "text" in data and isinstance(data["text"], str):
            return data["text"]
        
        return None
    
    def _replace_prompt(self, data: Dict[str, Any], new_text: str) -> Dict[str, Any]:
        """Reemplaza el prompt con versión neutral."""
        prompt_fields = ["prompt", "message", "input", "text", "content", "query"]
        
        for field in prompt_fields:
            if field in data and isinstance(data[field], str):
                data[field] = new_text
                return data
        
        return data
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas del middleware."""
        return {
            **self.stats,
            "pre_violation_rate": (
                self.stats["pre_filter_violations"] / self.stats["total_requests"] * 100
                if self.stats["total_requests"] > 0 else 0
            ),
            "post_violation_rate": (
                self.stats["post_analysis_violations"] / self.stats["total_requests"] * 100
                if self.stats["total_requests"] > 0 else 0
            ),
        }
