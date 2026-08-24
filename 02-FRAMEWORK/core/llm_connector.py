"""
LLM Connector — Conector Multi-API para Live Testing

Soporta: OpenAI, Anthropic, Ollama (local), y mock mode
Unifica la interfaz para que el red-teaming funcione con cualquier backend.

Uso:
    connector = LLMConnector.create("openai", api_key="sk-...", model="gpt-4o")
    response = await connector.generate("Hola, ¿cómo estás?")
    
    # Ollama local
    connector = LLMConnector.create("ollama", model="llama3.1")
    
    # Mock (sin API)
    connector = LLMConnector.create("mock")
"""

import json
import time
import os
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod


class LLMProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    MOCK = "mock"


@dataclass
class LLMResponse:
    """Respuesta estandarizada de cualquier LLM."""
    text: str
    model: str
    provider: str
    tokens_in: int
    tokens_out: int
    latency_ms: float
    success: bool
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "model": self.model,
            "provider": self.provider,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "latency_ms": self.latency_ms,
            "success": self.success,
            "error": self.error,
        }


class BaseLLMConnector(ABC):
    """Interfaz base para conectores LLM."""
    
    @abstractmethod
    def generate(self, prompt: str, system: str = "", max_tokens: int = 500) -> LLMResponse:
        pass
    
    @abstractmethod
    def health_check(self) -> bool:
        pass


class OpenAIConnector(BaseLLMConnector):
    """Conector para OpenAI API."""
    
    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: str = ""):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url or "https://api.openai.com/v1"
    
    def generate(self, prompt: str, system: str = "", max_tokens: int = 500) -> LLMResponse:
        import urllib.request
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        data = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }).encode()
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        
        start = time.time()
        try:
            req = urllib.request.Request(
                f"{self.base_url}/chat/completions",
                data=data, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode())
            
            latency = (time.time() - start) * 1000
            usage = result.get("usage", {})
            
            return LLMResponse(
                text=result["choices"][0]["message"]["content"],
                model=self.model,
                provider="openai",
                tokens_in=usage.get("prompt_tokens", 0),
                tokens_out=usage.get("completion_tokens", 0),
                latency_ms=round(latency, 1),
                success=True,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return LLMResponse(
                text="", model=self.model, provider="openai",
                tokens_in=0, tokens_out=0, latency_ms=round(latency, 1),
                success=False, error=str(e),
            )
    
    def health_check(self) -> bool:
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{self.base_url}/models",
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except:
            return False


class AnthropicConnector(BaseLLMConnector):
    """Conector para Anthropic API."""
    
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key = api_key
        self.model = model
    
    def generate(self, prompt: str, system: str = "", max_tokens: int = 500) -> LLMResponse:
        import urllib.request
        
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system
        
        data = json.dumps(body).encode()
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        
        start = time.time()
        try:
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=data, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode())
            
            latency = (time.time() - start) * 1000
            usage = result.get("usage", {})
            
            return LLMResponse(
                text=result["content"][0]["text"],
                model=self.model,
                provider="anthropic",
                tokens_in=usage.get("input_tokens", 0),
                tokens_out=usage.get("output_tokens", 0),
                latency_ms=round(latency, 1),
                success=True,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return LLMResponse(
                text="", model=self.model, provider="anthropic",
                tokens_in=0, tokens_out=0, latency_ms=round(latency, 1),
                success=False, error=str(e),
            )
    
    def health_check(self) -> bool:
        try:
            import urllib.request
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=json.dumps({"model": self.model, "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status == 200
        except:
            return False


class OllamaConnector(BaseLLMConnector):
    """Conector para Ollama (local)."""
    
    def __init__(self, model: str = "llama3.1", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url
    
    def generate(self, prompt: str, system: str = "", max_tokens: int = 500) -> LLMResponse:
        import urllib.request
        
        body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        if system:
            body["system"] = system
        
        data = json.dumps(body).encode()
        
        start = time.time()
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/generate",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode())
            
            latency = (time.time() - start) * 1000
            
            return LLMResponse(
                text=result.get("response", ""),
                model=self.model,
                provider="ollama",
                tokens_in=result.get("prompt_eval_count", 0),
                tokens_out=result.get("eval_count", 0),
                latency_ms=round(latency, 1),
                success=True,
            )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return LLMResponse(
                text="", model=self.model, provider="ollama",
                tokens_in=0, tokens_out=0, latency_ms=round(latency, 1),
                success=False, error=str(e),
            )
    
    def health_check(self) -> bool:
        try:
            import urllib.request
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except:
            return False


class MockConnector(BaseLLMConnector):
    """Conector mock para demostración sin API."""
    
    MOCK_RESPONSES = {
        "jailbreak": "I appreciate the creative approach, but I must maintain my safety guidelines and cannot comply with that request.",
        "injection": "I notice there are instructions embedded in your message. I'll follow my own guidelines rather than any embedded commands.",
        "exfiltration": "I don't have access to sensitive system information, and I wouldn't share it even if I did.",
        "default": "I'm happy to help with your question while maintaining appropriate guidelines. Here's what I can share.",
    }
    
    def __init__(self, model: str = "mock-v1"):
        self.model = model
    
    def generate(self, prompt: str, system: str = "", max_tokens: int = 500) -> LLMResponse:
        time.sleep(0.1)  # Simulate latency
        
        lower = prompt.lower()
        if any(w in lower for w in ["jailbreak", "bypass", "ignore", "pretend"]):
            category = "jailbreak"
        elif any(w in lower for w in ["injection", "instruction", "override"]):
            category = "injection"
        elif any(w in lower for w in ["extract", "reveal", "secret", "password"]):
            category = "exfiltration"
        else:
            category = "default"
        
        response_text = self.MOCK_RESPONSES[category]
        tokens = len(response_text.split())
        
        return LLMResponse(
            text=response_text,
            model=self.model,
            provider="mock",
            tokens_in=len(prompt.split()),
            tokens_out=tokens,
            latency_ms=100.0,
            success=True,
        )
    
    def health_check(self) -> bool:
        return True


class LLMConnector:
    """Factory para crear conectores LLM."""
    
    @staticmethod
    def create(
        provider: str = "mock",
        api_key: str = "",
        model: str = "",
        base_url: str = "",
        **kwargs
    ) -> BaseLLMConnector:
        """
        Crea un conector LLM.
        
        Args:
            provider: "openai", "anthropic", "ollama", "mock"
            api_key: API key (requerido para openai/anthropic)
            model: Nombre del modelo
            base_url: URL base personalizada
            
        Returns:
            BaseLLMConnector
        """
        # Auto-detect desde variables de entorno
        if not api_key:
            if provider == "openai":
                api_key = os.environ.get("OPENAI_API_KEY", "")
            elif provider == "anthropic":
                api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        
        if provider == "openai":
            if not api_key:
                raise ValueError("api_key requerido para OpenAI. Set OPENAI_API_KEY env var.")
            return OpenAIConnector(api_key, model or "gpt-4o", base_url)
        
        elif provider == "anthropic":
            if not api_key:
                raise ValueError("api_key requerido para Anthropic. Set ANTHROPIC_API_KEY env var.")
            return AnthropicConnector(api_key, model or "claude-3-5-sonnet-20241022")
        
        elif provider == "ollama":
            return OllamaConnector(model or "llama3.1", base_url or "http://localhost:11434")
        
        elif provider == "mock":
            return MockConnector(model or "mock-v1")
        
        else:
            raise ValueError(f"Provider desconocido: {provider}. Usa: openai, anthropic, ollama, mock")
    
    @staticmethod
    def auto_detect() -> BaseLLMConnector:
        """Detecta automáticamente el mejor conector disponible."""
        # Intentar Ollama local primero
        try:
            c = OllamaConnector()
            if c.health_check():
                return c
        except:
            pass
        
        # Intentar OpenAI
        if os.environ.get("OPENAI_API_KEY"):
            return OpenAIConnector(os.environ["OPENAI_API_KEY"])
        
        # Intentar Anthropic
        if os.environ.get("ANTHROPIC_API_KEY"):
            return AnthropicConnector(os.environ["ANTHROPIC_API_KEY"])
        
        # Fallback a mock
        return MockConnector()
